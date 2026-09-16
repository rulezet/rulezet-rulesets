rule _20160517_7dcf8f681a66a0d5b359e351a43da1c5_20160517_d4169926bc09_981 {
  meta:
    description = "datamaliciousorder - from files 20160517_7dcf8f681a66a0d5b359e351a43da1c5.js, 20160517_d4169926bc09a955ac4418055090cbe2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56a62be0861bc16e4ac2a05c0edf2ed364ddc8df0f78cd1b5418d30f0e925641"
    hash2       = "d6383a56aedee90d169c2198a92d1fbb4b9a6366573422d675a3cb93992ceffd"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* KJ  */, Currency, (true, false));" fullword ascii
    $s2 = "function Scott /* KJ  */(accinp0 /* KJ  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 " ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* KJ  */ = (123, Turkey); return devel0 /* KJ  */;};" fullword ascii
    $s4 = "DENMARK1 /* KJ  */= true;/* KJ  */" fullword ascii
    $s5 = "function Scott /* KJ  */(accinp0 /* KJ  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 " ascii
    $s6 = "place = /* KJ  */(/* KJ  */\"noitisop\").split(''/* KJ  */).reverse(/* KJ  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}