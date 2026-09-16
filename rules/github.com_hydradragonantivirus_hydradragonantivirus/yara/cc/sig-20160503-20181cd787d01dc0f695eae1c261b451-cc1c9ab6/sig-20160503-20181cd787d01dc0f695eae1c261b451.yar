rule sig_20160503_20181cd787d01dc0f695eae1c261b451 {
  meta:
    description = "datamaliciousorder - file 20160503_20181cd787d01dc0f695eae1c261b451.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d67ccfb85a692a07386ecfc17673f20fcc64bbbb7e93e76aae13638cade88953"

  strings:
    $s1  = "eval((function(){var n=[71,72,88,87,60,65,86,89,81,70,76,80,90,85,75,94,79,66,82,74];var a=[];for(var x=0;x<n.length;x++)a[n[x]]" ascii
    $s2  = "ar x=0;x<t.length;x++)g=g.split(k+r.charAt(x)).join(String.fromCharCode(t[x]));return g.split(k+'!').join(k);})('function tg@p@x" ascii
    $s3  = "8,4~GH@~break}Gr~Gi){var~216,88,7255~}function ~[pSC@yM(\"0~=pSC@yM(\"0~))+Gn(~Gi;if(~dvj@oepg()~@wf@n@w@i=~GV@~))+Gv(~\"GV~}GW~" ascii
    $s4  = "p@s\".lengthGgrhjG<GrDCgxDEj=\"@uf@t@nmb\"H#1H-@s@gMDiTa\"G`j@g@lo=72053}GrGN\"\"Ggujq@lw@p=@js@wEsrdh.length;while(@rhj@k@ujq@l" ascii
    $s5  = "(b+1)-32;h=b;b++;}else if(c==96){v=94*(n.length-32+s.charCodeAt(b+1))+s.charCodeAt(b+2)-32;h=b;b+=2;}else{continue;}if(f==null)f" ascii
    $s6  = "GExMh@gGd;G410034011045H\\'z@znDr@j,@mhxfs,false)GghkG@G6G.G;G5G1brG0GUG%G8G)G,G=G H3G+H!3;G422H)00039\")]G_k@iDCp@wTGJ54049H%42" ascii
    $s7  = "eval((function(){var n=[71,72,88,87,60,65,86,89,81,70,76,80,90,85,75,94,79,66,82,74];var a=[];for(var x=0;x<n.length;x++)a[n[x]]" ascii
    $s8  = "j(d@wv){switch(\"v@x@h@rSMyE\"G^GmH\"@mMj=72934H#@mMj===0GfEwu=\"vu@rs@ora\"};bG\"mm@pm=\"sv@n@i\"Ggt@oTGL@t@oT==0){GR0G^253Gsrs" ascii
    $s9  = "G\\\\var ~H\"xkirm=true;~){}GA~r sec@og=\"Eio@p~=(2426,5571,0)~ a@oeN=true;br~GC9~976,388,7305,~@xx@o=true;sw~Gl;case ~GG,~,4463" ascii
    $s10 = "6,6702,92H+)]()}}catch(igjy){}~eak;case Gmvar ~q@tEqfj(@js@wEsrdh,~reak;case trueGs~if(xkirm===1){};var~9,8217,9892,4520,1)~fals" ascii
    $s11 = "ccun()~=trueH#~ @h@zN@t=~;return ~;switch(~Gl};~(G`~G_@~(7071,19~==true){~@qnov@p(~){case ~(Gh~Gf@~\"Gh~c@pvgDh~h@zzn10~=true;;~" ascii
    $s12 = "@i@r\"H.1==1){va~G6y~eak;case \"mhNGu~ue:if(5=Gi){};~8430,1155,8729,3)~8,4G?8~@uS@t@lGI~i\"}GAtr~itch(7G^\"bhg~ m@m@s@oj=81664;~" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}