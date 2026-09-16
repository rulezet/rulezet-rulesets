rule _20160516_50dad93a6788b3beb89553787f6889d6_20160517_43e2f667c71d_1223 {
  meta:
    description = "datamaliciousorder - from files 20160516_50dad93a6788b3beb89553787f6889d6.js, 20160517_43e2f667c71daf9ea1b058070532c901.js, 20160517_94036beb6ad6694c592f415a5b22be1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e83cdda7013b273cf088a330bbc89302839d8cf2c8e187da48eb84bda9d5185f"
    hash2       = "4fee2e5c290d405ffca0431888c39d055aea501a193959a84338385d4691f690"
    hash3       = "4e5717d5b56f37855f2ab3c19b59cb1494a5c3761beff18e019cb26da046bacc"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* G  */, Currency, (true, false));" fullword ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* G  */ = (123, Turkey); return devel0 /* G  */;};" fullword ascii
    $s3 = "function Scott /* G  */(accinp0 /* G  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s4 = "DENMARK1 /* G  */= true;/* G  */" fullword ascii
    $s5 = "place = /* G  */(/* G  */\"noitisop\").split(''/* G  */).reverse(/* G  */).join('');" fullword ascii
    $s6 = "function Scott /* G  */(accinp0 /* G  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}