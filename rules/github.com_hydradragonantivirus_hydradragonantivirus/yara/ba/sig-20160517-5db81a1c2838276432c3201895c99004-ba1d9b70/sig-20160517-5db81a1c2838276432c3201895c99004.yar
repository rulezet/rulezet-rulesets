rule sig_20160517_5db81a1c2838276432c3201895c99004 {
  meta:
    description = "datamaliciousorder - file 20160517_5db81a1c2838276432c3201895c99004.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6df76e4fb23a67c2753e9ccb91452c1bdec2bb588b479b7b40f624dd8e59132e"

  strings:
    $s1 = "var g4sbnk='vjykk1aenzsbrzggox nwzuamlmaug2vvzta1do4f3pwqq4i1setcxwyctq2exbn31falvwfuarxa2=eesqi\\'pmqyttapzhfcnfloinflxhiifhaam" ascii
    $s2 = "WScript.lister=5;   qdvscya1t=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"+\"th\"])  {      ivnvgx31=5465;" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}