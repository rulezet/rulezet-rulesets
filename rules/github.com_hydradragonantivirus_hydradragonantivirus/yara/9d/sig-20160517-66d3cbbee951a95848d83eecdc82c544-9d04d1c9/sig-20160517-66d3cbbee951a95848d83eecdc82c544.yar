rule sig_20160517_66d3cbbee951a95848d83eecdc82c544 {
  meta:
    description = "datamaliciousorder - file 20160517_66d3cbbee951a95848d83eecdc82c544.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52abbf840c1675cbb006e570c60fc9697e1ae46e742b867a9a20187605869228"

  strings:
    $s1 = "var vsp2='vx4iqhaxee1urakrji do3a3qtykblaa3oxjoyhni2mefgdfqfauvo3iwce1kmiytofemr3j=w3usl\\'dqucytsh4ydcda4yjnmdv32iamncoffhrv4ut" ascii
    $s2 = " WScript.lister=5;   lbjne3rpvw=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"+\"th\"])  {      bge3gsmh=999" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}