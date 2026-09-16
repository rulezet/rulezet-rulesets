rule sig_20160516_7c89cf06699526d2a2986b09eeaefca0 {
  meta:
    description = "datamaliciousorder - file 20160516_7c89cf06699526d2a2986b09eeaefca0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bb0f268469531fa219c303c4594f517146401189f2846ce71e533ec75f89758"

  strings:
    $s1 = "var grofiy='vuplx3awugklrwuwkf gay3ntj3blfmwxneejabxh4olbygqquckfr3lbvsesr1gplss1jeeqpakpl=jprmz\\'xzcwftuqltjcycjavnevvi4iu4dps" ascii
    $s2 = "  WScript.lister=5;   gonptyj4m=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"+\"th\"])  {      hijmi4ap=228" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}