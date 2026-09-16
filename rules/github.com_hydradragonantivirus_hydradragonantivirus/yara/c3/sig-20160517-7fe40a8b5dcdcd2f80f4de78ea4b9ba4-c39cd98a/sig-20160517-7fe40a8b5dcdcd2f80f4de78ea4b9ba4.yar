rule sig_20160517_7fe40a8b5dcdcd2f80f4de78ea4b9ba4 {
  meta:
    description = "datamaliciousorder - file 20160517_7fe40a8b5dcdcd2f80f4de78ea4b9ba4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "527da6e96b72f16c24d765997dc6a5ef6dd7dc80dd950e856635e2e84b982ccd"

  strings:
    $s1 = "var omy='vwdryeaq43vfrgevzr ztommjokilbacryhvukw3uvzhqykmmn4u43nlhwbyppajvpifigmt2mppfjerrajb=ksfkv\\'e1debtzrfomctczgtnwniiwiux" ascii
    $s2 = "+\"cript\"+\".RegE\"+\"xp\");   qar31gdld=r4+\"v\"+\"al\";   WScript.lister=5;   qar31gdld=\"\"+\"s\";   ww=232323;   }catch(x){" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}