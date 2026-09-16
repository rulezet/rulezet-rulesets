rule sig_20160516_8b65e636e5522d05831ff9a9e0dffb26 {
  meta:
    description = "datamaliciousorder - file 20160516_8b65e636e5522d05831ff9a9e0dffb26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71f7a4c81163cf4615c68e36b570223b129e429ac835cd818c585a02a75ed50a"

  strings:
    $s1 = "var s1ou='vwva4laq1n1kryjlzg jlcz2ogt11fotei3hvsecwhhwthetupydgxomfiueekb3kc1wskuv=nm43j\\'atcw3tys1d4ctuihonavuugiyb4k1fagn2iuh" ascii
    $s2 = "vm=r4+\"v\"+\"al\";   WScript.lister=5;   xoumfyvm=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"+\"th\"])  " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}