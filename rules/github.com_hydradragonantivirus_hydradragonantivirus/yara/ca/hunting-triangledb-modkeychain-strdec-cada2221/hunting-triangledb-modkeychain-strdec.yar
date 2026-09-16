rule Hunting_Triangledb_ModKeychain_Strdec {
    meta:
        author = "@captainGeech42"
        description = "Look for the string decryption routine code in TriangleDB's keychain stealing module."
        date = "2024-01-06"
        version = "1"
        DaysofYARA = "6/100"
        reference = "https://securelist.com/triangulation-validators-modules/110847/"
        hash = "64f36b0b8ef62634a3ec15b4a21700d32b3d950a846daef5661b8bbca01789dc"
    strings: 
                                        $c1 = {
                        a8 ?? ?f f8
                        e9 ?? ?0 b9
                        0a 69 69 38
                        e8 0? ?0 f9
                        e9 ?? ?0 b9
                        0B 69 69 38
                        4a 01 0B 4a
                        eb 0? ?0 b9
                        4a 01 0b 4a
                        e8 0? ?0 f9
                        e9 ?? ?0 b9
                        08 01 09 8b
                        0a 01 00 39
                        e8 0? ?0 b9
                        08 05 00 11
        }

    condition:
        (
            uint32(0) == 0xfeedface or             uint32(0) == 0xcefaedfe or             uint32(0) == 0xfeedfacf or             uint32(0) == 0xcffaedfe or             uint32(0) == 0xcafebabe or             uint32(0) == 0xbebafeca            ) and (
            filesize < 2MB and
            all of them
        )
}