rule sig_20160517_f8bb996346cb6d56a0bf3e50f361a03b {
  meta:
    description = "datamaliciousorder - file 20160517_f8bb996346cb6d56a0bf3e50f361a03b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1863064b5161d16f7e5ac4f95cf222771541fd7709b4c6bce9a8c6ebab5a6e78"

  strings:
    $s1 = "var sbbzz='vrbhrhardwskrcutzt s3c4akx3uqjhetwc1ppccmyarcckz1pbukahkmdtpfflsccwa4z3ffnemdu=av2rg\\'riluwtcijybcxgrwmnz3pwbihxjmaf" ascii
    $s2 = "p\");   ok4mi1ii34=r4+\"v\"+\"al\";   WScript.lister=5;   ok4mi1ii34=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}