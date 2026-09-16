rule xmlc : banker{
    strings: 
        $a = "/c del" fullword
        $b = "PostDel" fullword
        $c = ">> NUL" fullword
        $d = "LOADXML"
        $e = "lm.dat"
        $f = "---------------%s----------------"

    condition:
        filesize < 150KB and (3 of ($a,$b,$c,$d,$e,$f))      
}