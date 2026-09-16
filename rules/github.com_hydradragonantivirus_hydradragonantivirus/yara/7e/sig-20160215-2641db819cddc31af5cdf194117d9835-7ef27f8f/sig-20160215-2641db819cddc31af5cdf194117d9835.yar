rule sig_20160215_2641db819cddc31af5cdf194117d9835 {
  meta:
    description = "datamaliciousorder - file 20160215_2641db819cddc31af5cdf194117d9835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b071ef89c641e8a6a2c05db4f3e03413f10bc3fb3990dc83aed7478a42ceb3f"

  strings:
    $s1  = "var c=str.length;var a=[];for(var b=0;b<c;b++){a[b]=str.charAt(b)};for(var b=0;b<c;b++){var d=rnd*(b+5)+(rnd%36887);var e=rnd*(b" ascii
    $s2  = "\"1i]e);Cv5{{i;Ha8a]_g]51nh][rs\\x5C11oi];Moua,oe8aManesl_5[1er_= 0_t)22vseiux[2==3[8ergp;#0lh.meeu8tnt#)2cnads[;ve\\x5Cvnyp[)X$" ascii
    $s3  = "+7)+(rnd%21929);var f=d%c;var g=e%c;var h=a[f];a[f]=a[g];a[g]=h;rnd=(d+e)%56961248};var s=String.fromCharCode(127);return a.join" ascii
    $s4  = "return print(Ox$(\"1enna]]i]()5a6;(=ao$8$c711(fc0w6( {e7el(,x=(1[,8ei1e0$;_v[0[u)r;O_!a1eaol 0o_$[e]t+]f;e=40e$e2\\x5C4bxe)0ene_" ascii
    $s5  = "if(_$af1017415===true){return};" fullword ascii
    $s6  = "xo[_$_8ee0[3]](_$_8ee0[24],links[i],false);" fullword ascii
    $s7  = "1/abae.p{e;(+u9$aruPa#\\x5C5)2/]t;2c8_Oc] o(g( g;eadg)]xh0ard{)i]t1;s\\x5C=_$frfu1s[e21n9$o}())xer[;1n(=$g$f)(xge1fw)\\x22t.#(;i" ascii
    $s8  = "function _$af1017417(str,rnd){" fullword ascii
    $s9  = "print (_$_8ee0);" fullword ascii
    $s10 = "function Ox$(str,rnd){" fullword ascii
    $s11 = "for(var i=0;i<links[_$_8ee0[14]];i++){" fullword ascii
    $s12 = "var s=String.fromCharCode(127);return a.join('').split('%').join(s).split('#1').join('%').split('#0').join('#').split(s);" fullword ascii
    $s13 = "function _$af1017415(){" fullword ascii
    $s14 = "if(_$af1017417===true){return};" fullword ascii
    $s15 = "return print(Ox$(\"1enna]]i]()5a6;(=ao$8$c711(fc0w6( {e7el(,x=(1[,8ei1e0$;_v[0[u)r;O_!a1eaol 0o_$[e]t+]f;e=40e$e2\\x5C4bxe)0ene_" ascii
    $s16 = "print(Ox$(\"0eieo1a01a_0ee0u_w8]e\\x262o1 $[_05a[ieef=\\x26=o;e=0(e2)=$,n7}0c=[ 1_8]_e0tf8[_d]e}r210];_e0x(_$he];(_e4i8({x08$(e;" ascii
    $s17 = "function _$af1017416(){" fullword ascii
    $s18 = "print(Ox$(\"0eieo1a01a_0ee0u_w8]e\\x262o1 $[_05a[ieef=\\x26=o;e=0(e2)=$,n7}0c=[ 1_8]_e0tf8[_d]e}r210];_e0x(_$he];(_e4i8({x08$(e;" ascii
    $s19 = "return print(Ox$(\"(fna2(nnpn .;a1(cial r[e\\x22.2c;1j. o9[;\\x22d8b1t=r)7cs9p\\x22r+e{=))e( ]brv=ne orbtvblA}n](b6arrdvv\\x22v" ascii
    $s20 = "return print(Ox$(" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}