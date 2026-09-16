rule sig_20160403_7018c2fe79d5436cdb08e106e928628b {
  meta:
    description = "datamaliciousorder - file 20160403_7018c2fe79d5436cdb08e106e928628b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86923dcf8d2d24e9ac14fde3f52c7c146f283e40fc99bdc554cb2d689d18efc2"

  strings:
    $x1 = "var f76='+\"',o30='exe \"',m42='he',r45=') {',a48='\".',z11=' un',a26='z *',g41='end(',p50='.S',l55='(f',t70='t.Cre',q77='dEnvi'" ascii
    $s2 = "='eLin',b57='lgori',c72='.Writ',l87=' f',d68='q);',x16='max ',f86='eO',q98=' /F /',q81=' soft',z77='xists',d83='p ',f21='DD ',v3" ascii
    $s3 = "Line('+'\"w'+q19+'e enc'+f73+u37+'ed'+' usin'+p78+'stro'+'ng RS'+m98+'024 a'+b57+'thm'+' with'+j39+z11+n21+' key.'+'\"); f'+a33+" ascii
    $s4 = "}',y98='pt.',e85='e ',q94='ptor',t36='{ for',z1='teL',n58=' sear',w74='\"+ad+',i98='p.Wri',b92='.t',s89='WAR',i80=' *.vc',e42='+" ascii
    $s5 = "\"  ',p6='\"Wind',n27='Li',d93=' not',h75='Writ',a91=' \"',a33='p.W',l20='3 day',c91='tan',w60='fp.Wr',z61='.p',j46='T.tx',d22='" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}