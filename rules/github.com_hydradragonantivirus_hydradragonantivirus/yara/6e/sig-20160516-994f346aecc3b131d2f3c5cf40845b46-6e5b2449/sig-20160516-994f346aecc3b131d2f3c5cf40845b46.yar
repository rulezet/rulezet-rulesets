rule sig_20160516_994f346aecc3b131d2f3c5cf40845b46 {
  meta:
    description = "datamaliciousorder - file 20160516_994f346aecc3b131d2f3c5cf40845b46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "428f3f1275c63b5d75f20fa65920443411f21cdc158c691b8dfac9b95c24a699"

  strings:
    $s1 = "var hmq1='vidphyaff2eirgtjn1 cdfwitqacetgzo2i1zgjeoubny4edubl1z3dtdghabbkeztekoh42=i3lqr\\'xxqkctu1ryzcjzcagnpxvpwioqlzufphw33ue" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}