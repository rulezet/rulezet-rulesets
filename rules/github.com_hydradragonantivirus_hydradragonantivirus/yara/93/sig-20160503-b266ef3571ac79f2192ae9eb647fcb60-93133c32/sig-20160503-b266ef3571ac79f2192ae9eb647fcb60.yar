rule sig_20160503_b266ef3571ac79f2192ae9eb647fcb60 {
  meta:
    description = "datamaliciousorder - file 20160503_b266ef3571ac79f2192ae9eb647fcb60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b19ab68642a43a4aa4f32b6e13eb28577929a54bba59215bc3221b9a1ff85bc"

  strings:
    $s1  = "ar b=0;b<g.length;b++)p=p.split(e+y.charAt(b)).join(String.fromCharCode(g[b]));return p.split(e+'!').join(e);})('function pr@hrm" ascii
    $s2  = "eval((function(){var a=[71,89,60,86,82,72,87,94,85,76,74,88,90,79,81,65,75,70,66,80];var z=[];for(var b=0;b<a.length;b++)z[a[b]]" ascii
    $s3  = "eval((function(){var a=[71,89,60,86,82,72,87,94,85,76,74,88,90,79,81,65,75,70,66,80];var z=[];for(var b=0;b<a.length;b++)z[a[b]]" ascii
    $s4  = "(r+1)-32;c=r;r++;}else if(j==96){m=94*(a.length-32+o.charCodeAt(r+1))+o.charCodeAt(r+2)-32;c=r;r+=2;}else{continue;}if(f==null)f" ascii
    $s5  = "==\"@wNaSfaM\"){Giaz@whT){cGH c@q@vy@pu=56590GGtrueY+y@jC@txG8rkf=17336G6\"tx@pNe@zfE\"Go@gn@kf@jp=77678GD@wED@o=61092};break}}G" ascii
    $s6  = " wlE=37206GG\"CSv@z@x\"Go@ues=4278;break;cGH CEvi@tbd=32898G];Gnxv@mEG+GOGyGU1=(xv@mE=G2G#G!GtGU1&&GU2Gkm@w@otG91G3G/64,781,2);G" ascii
    $s7  = "r@heir,b@hc,ct@jE,ig@vSECGksye=\"@yTak@hCT\"GjxtonGlGJwsv@otaGal@li=[(7283,6911,8985,1297,4160Y/4,5254,4516,50Gv,@vctive@r@tbjec" ascii
    $s8  = "#G!Gjza@uGq;;GnGf=\"\"GnmTfT=Ip@ts@m.length;while(GW@imTfT-(21G3G/64,781,2)GblcCG2G#G!GnEE@p@oyG98,56GvGnxb@lnG+EE@p@oy)Gjlz@hmC" ascii
    $s9  = "var~w=64462G{5=~24G{TyqD@qM~jrGL~Gy@t@jxzcid~ TyqD@qMp=313~))+Y%t@m((~G]var ~@qrlC@yk@k@l~GjlTy@wl~;break;case ~ase true:var~Gi1" ascii
    $s10 = "){ca~GP@~=Y1g@l(\"0~[Y1g@l(\"0~=qM@r@qkbI(~C@wc@uhcu()~GW);~}function ~Gl;if(~(28,5653,1~==Gq){}~@k@sqCtqoh~Defa@vbE10~G[@~w@u@m" ascii
    $s11 = "][kh@qzT@h@h]G[q@qtEGJxgTM(kT@o){GIse GsGoY#svu@y=\"n@owcnp@jGpY#svu@y=G-;case 53Gr r@yfE@ggT=16357G{r@yfE@ggT==0GkuzExe@wGlG6Gr" ascii
    $s12 = "se}G\\\\~=(1311,2613,326~88,4863,3798,7~pG8~og@pjDkmGq}~}GG~\"GG~GZvar ~=GW+(2~7,9011,9202,3~77,4901,4127,~,7704,6594,75~{case 1" ascii
    $s13 = "@s~q@hD@qv()~7307,2677~=Gl){~;return ~;Gi~;break};~Gc@~64,781,2~@lEqq@h@~(Gk~Gk@~()Gn~){case ~;Syo@kt~csxM@wI~,8515,4~rueG{~swit" ascii
    $s14 = "08,2975,7827,266,3773,4880,1)]()}}catch(w@z@gT){}~G#9~97,3429,841,6745,0)~GGfalse:~4,5837,8845,880,58~G\\'a~ar @rn@x@lGl};~G)i~i" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}