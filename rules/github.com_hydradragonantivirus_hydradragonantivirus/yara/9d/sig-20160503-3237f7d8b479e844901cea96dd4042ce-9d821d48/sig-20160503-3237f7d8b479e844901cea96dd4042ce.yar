rule sig_20160503_3237f7d8b479e844901cea96dd4042ce {
  meta:
    description = "datamaliciousorder - file 20160503_3237f7d8b479e844901cea96dd4042ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37fe537ab29c5d13f6cbe8f6a7d0ff89e5ecb500dbc47c2726c8c8ceb573a492"

  strings:
    $s1  = "ar j=0;j<z.length;j++)h=h.split(y+g.charAt(j)).join(String.fromCharCode(z[j]));return h.split(y+'!').join(y);})('function Ihirp(" ascii
    $s2  = "eval((function(){var b=[66,86,90,71,65,94,80,60,88,87,85,79,82,70,76,89,81,74,75,72];var r=[];for(var j=0;j<b.length;j++)r[b[j]]" ascii
    $s3  = "h(Bagm@g@j=\"C\"BQgm@g@jB>Emxdw@xBRmTf@ga=\"@kBAmTf@gaB>yBH{switch(4)Bd0B}5BFju@oI=57098B!chs@p=\"un@o@z\"B.oax@q@oxC=13187B4@yS" ascii
    $s4  = "h(~BT2~}BV~B_);~;return ~(B\\\\~=nm@x(\"0~[nm@x(\"0~B]@~;switch(~@rbt@qi=~u@pNak()~@pb@oTM=~){}Bo~;breBu~Ba@~(Bc~6V.35~b@xoCbb~B" ascii
    $s5  = "engthBoB_B5BoMMyBbBs1==191Baa@qdcBb}BoB;\"\"B`g@qvdlv=i@r@qlixv.length;while(B_@n@g@qvdlv-(BCB),2)B\\\\oNIf@zN@jmB5Boq@kqrCmj=BG" ascii
    $s6  = "(d+1)-32;l=d;d++;}else if(o==96){t=94*(b.length-32+q.charCodeAt(d+1))+q.charCodeAt(d+2)-32;l=d;d+=2;}else{continue;}if(n==null)n" ascii
    $s7  = "eval((function(){var b=[66,86,90,71,65,94,80,60,88,87,85,79,82,70,76,89,81,74,75,72];var r=[];for(var j=0;j<b.length;j++)r[b[j]]" ascii
    $s8  = "rTgm@ipz=67710;break}}BQfV#B<V!s(f@pwBaljS=parseInt(f@pw)BQljSB>ElEgBRpMz@ufe@i=\"fBApMz@ufe@iB>wB@{Br@zMlgm@vTb=\"rBAzMlgm@vTbB" ascii
    $s9  = "@hwMB>V!@omfs(Cbkhy){B#B$B\\'B BqB&B=B!@vB%Bu;B`kttdMe@y=q@iSEjB]N@ij=Nt@zwB]t@k@gIT@u=BXBoywf=wB@B`oaE@v@p=Emxdw@xBUyBy=\"t\"Bo" ascii
    $s10 = "@td@uDu\";brB @idta@geBbB9348:BroT@vwrd=\"lnx@wqBpoT@vwrd==231){V+eakBO4B7SNuov=65391B8Cg@i@sBf@zCje@v=23378;brB @saus@g@q=19690" ascii
    $s11 = "u@hM(i@r@qlixv,~Br@z@jeM@ty@z=fal~seBV2){case \"~qDbS=\"u@wEay@u\";bre~\"@o@j@z@wf@ppBp@~zpD\"B}5===1){};br~6,8965,4833,1771,1)~" ascii
    $s12 = "{Br~=fV#~)Bo~{case ~=Bt;~\":Br~85,698~oSzuey~wja@om~@s@u@w~d@zw10~wp@xrb~wjeouD~=kw@q(~;Br~\"Bs~@vtC=~var ~;if(~true~ak};~0630~" ascii
    $s13 = "66};~))+mBB(~){}B9~ucI@hvEBT~B[;;var ~=(68V 811,0)~,5973,9616,869~)Bd1:var ~B9\"~;break;case ~=falseBa~Sl@p@mx@ydk=~B>@~vtC==Bt)" ascii
    $s14 = "17,3B|382,9615,8782,4682V&0,1),pIunT@t@k][(1617,3B|382,9615,8782,4682V&0,1)]()}}catch(c@x@kp){}~eak;case false:Br~}B91:var ~@v@k" ascii
    $s15 = "~}function ~)+k@kCug((~ok@x@mMl()~\"BI~@vdN@kx@q(~8053,7281,~case Bt:~)BI~===0Ba~B_+(2~@t@o@wkj()~BQ@~nN@ox@xNC~Bb;br~]BQ~){swit" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}