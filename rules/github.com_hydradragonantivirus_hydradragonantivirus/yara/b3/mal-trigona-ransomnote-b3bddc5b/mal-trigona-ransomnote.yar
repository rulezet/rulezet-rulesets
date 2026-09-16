rule MAL_Trigona_ransomnote {
    meta:
        description = "Matches strings found in Trigona ransom notes."
        last_modified = "2024-03-29"
        author = "@petermstewart"
        DaysofYara = "89/100"

    strings:
        $a1 = "3x55o3u2b7cjs54eifja5m3ottxntlubhjzt6k6htp5nrocjmsxxh7ad.onion"
        $b1 = "<title>ENCRYPTED</title>"
        $b2 = "the entire network is encrypted"
        $b3 = "your business is losing money"
        $b4 = "All documents, databases, backups and other critical data were encrypted and leaked"
        $b5 = "The program uses a secure AES algorithm"
        $b6 = "decryption impossible without contacting us"
        $b7 = "To recover your data, please follow the instructions"
        $b8 = "Download Tor Browser"
        $b9 = "Open decryption page"
        $b10 = "Auth using this key"

    condition:
        filesize < 20KB and
        7 of them
}