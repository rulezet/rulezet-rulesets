rule sig_20151025_ec2c4bcfccf39d6d7c8d4ee9d6959055 {
  meta:
    description = "datamaliciousorder - file 20151025_ec2c4bcfccf39d6d7c8d4ee9d6959055.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "447757d8f716bafc3165ecf8fd1c864cd2a5d29e20f46331ed79e32e1e2ee6aa"

  strings:
    $s1  = "var str=\"55515C5E050A001D240C05120108050A004A070B095E275E120D010A17120B0D1607054A0A01105E17555E555050515350515151565E56\"; func" ascii
    $s2  = "; function qsq() { lgm += '.com'; }; function slwn() { lgm += 'DODB'; }; function dgh() { lgm += ' };'; }; function omnc() { lgm" ascii
    $s3  = "hvyq() { lgm += '\"%T'; }; function xaq() { lgm += '.exe\"'; }; function mhd() { lgm += '1; x'; }; function ahhk() { lgm += ' 1'" ascii
    $s4  = " }; function mtw() { lgm += '\"GET'; }; function wdis() { lgm += '; x'; }; function fmb() { lgm += 'i]+\"/'; }; function res() {" ascii
    $s5  = "m += 'Creat'; }; function ocja() { lgm += 'EM'; }; function log() { lgm += ' var'; }; function uezc() { lgm += 'tr+\"'; }; funct" ascii
    $s6  = "u() { lgm += ' = W'; }; function qesr() { lgm += 'ion '; }; function zblv() { lgm += 'rom'; }; function jwr() { lgm += '.gro'; }" ascii
    $s7  = "}; function yno() { lgm += ' > 1'; }; function dri() { lgm += 'iati'; }; function kogt() { lgm += '.Str'; }; function gche() { l" ascii
    $s8  = "ion osx() { lgm += '; '; }; function nokl() { mdbs += 'ev'; };  function cejt() { lgm += 'com'; }; function gkk() { lgm += 'fn+'" ascii
    $s9  = " { lgm += 'ct(\"'; }; function bhp() { lgm += 'xe\",1'; }; function mwox() { lgm += ' xo.'; }; function acxy() { lgm += 'it'; };" ascii
    $s10 = " dnn() { lgm += 'eak;'; }; function efyy() { lgm += '31'; }; function ruxv() { lgm += 'sit'; }; function nrs() { lgm += 'open(';" ascii
    $s11 = "tion dsy() { lgm += 'ring'; }; function dwou() { lgm += '== '; }; function lno() { lgm += 'er'; }; function bev() { lgm += 'xo.'" ascii
    $s12 = "'; }; function uvie() { lgm += 'xa.ty'; }; function lsvr() { lgm += '\"w'; }; function nmeb() { lgm += 'ar ws'; }; function japb" ascii
    $s13 = "() { lgm += 'xa.si'; }; function lbm() { lgm += 'ar '; }; function zdc() { lgm += '\".sp'; }; function htj() { lgm += '20'; }; v" ascii
    $s14 = "; }; function hhgb() { lgm += 'n+n+\"'; }; function nwpo() { lgm += ' WSc'; }; function kwww() { lgm += 'er)'; }; function jnwq(" ascii
    $s15 = "{ lgm += 'Creat'; }; function qad() { lgm += '<='; }; function ivn() { lgm += ', f'; }; function qgr() { lgm += '0) '; };lwns();" ascii
    $s16 = "m += 's('; }; function pom() { lgm += 'ry {'; }; function jdx() { lgm += ') { }'; }; function qgvq() { lgm += 'ndE'; }; function" ascii
    $s17 = "dis(); lbq(); ruxv(); qesr(); sxgh(); japb(); vtvm(); tmk(); away(); dxy(); hhgb(); xaq(); jse(); iam(); idt(); ghp(); eow(); gk" ascii
    $s18 = "m += '{ x'; }; function lwy() { lgm += 'e('; }; function atn() { fzv = this; };  function irbo() { lgm += 'n++) '; }; function d" ascii
    $s19 = "= 'ript.'; }; function aqa() { lgm += 'P\"'; }; function kisa() { lgm += 'vers'; }; function fkq() { lgm += 'pe = '; }; function" ascii
    $s20 = " { lgm += 'tSt'; }; function rmmt() { lgm += 'WScri'; }; function kqr() { lgm += ' ='; }; function ukwt() { lgm += 'tc'; }; func" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}