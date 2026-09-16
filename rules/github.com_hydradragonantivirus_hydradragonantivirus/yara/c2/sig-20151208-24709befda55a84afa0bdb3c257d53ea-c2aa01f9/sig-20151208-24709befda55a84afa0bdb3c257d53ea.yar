rule sig_20151208_24709befda55a84afa0bdb3c257d53ea {
  meta:
    description = "datamaliciousorder - file 20151208_24709befda55a84afa0bdb3c257d53ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e865cd8879076e37354b237673ef865b59ca30d9cf29c7d3fbfd22bcbbd2b4fd"

  strings:
    $s1  = "function WCzeSEj(aVGvuAdyvRrLOkVpKjUoOQXaiMrUYcivtGTS) {return !isNaN(parseFloat(aVGvuAdyvRrLOkVpKjUoOQXaiMrUYcivtGTS)) && isFin" ascii
    $s2  = "function WCzeSEj(aVGvuAdyvRrLOkVpKjUoOQXaiMrUYcivtGTS) {return !isNaN(parseFloat(aVGvuAdyvRrLOkVpKjUoOQXaiMrUYcivtGTS)) && isFin" ascii
    $s3  = "push(\"59\");u.push(\"13\");u.push(\"10\");u.push(\"118\");u.push(\"97\");u.push(\"114\");u.push(\"32\");u.push(\"104\");u.push(" ascii
    $s4  = "push(\"10\");u.push(\"9\");u.push(\"9\");u.push(\"32\");u.push(\"32\");u.push(\"32\");u.push(\"32\");u.push(\"98\");u.push(\"114" ascii
    $s5  = ");return VIuKW;}function eVzDOTRjvcGdSzg(aOWNfGAeXJgxDfDZj){eval(aOWNfGAeXJgxDfDZj)}" fullword ascii
    $s6  = "push(\"46\");u.push(\"67\");u.push(\"114\");u.push(\"101\");u.push(\"97\");u.push(\"116\");u.push(\"101\");u.push(\"79\");u.push" ascii
    $s7  = "var LKGlFqsgtFAUt=[];for(nEtZtVF=(-933+933)/206;nEtZtVF<(125893+187)/985;nEtZtVF++){LKGlFqsgtFAUt[nEtZtVF]=String.fromCharCode(n" ascii
    $s8  = "function iBhtFAZKbIMlFWTAAARlsoSJxyKtVHgzzwJEPblrYSzHuvWbupXfaY(ULRfGzeokvAXM,LGxUbolxYzuLuk){ return LKGlFqsgtFAUt[fronq(ULRfGz" ascii
    $s9  = "OZsyfVYx[KuLdERZlRqN]=(-265+265)/439; while(true) { if(LOZsyfVYx[KuLdERZlRqN] > Ojeht[KuLdERZlRqN].length-(674+296)/970) { break" ascii
    $s10 = "push(\"32\");u.push(\"32\");u.push(\"32\");u.push(\"75\");u.push(\"76\");u.push(\"97\");u.push(\"32\");u.push(\"61\");u.push(\"3" ascii
    $s11 = "push(\"118\");u.push(\"41\");u.push(\"32\");u.push(\"32\");u.push(\"123\");u.push(\"13\");u.push(\"10\");u.push(\"9\");u.push(\"" ascii
    $s12 = "push(\"57\");u.push(\"49\");u.push(\"51\");u.push(\"55\");u.push(\"51\");u.push(\"54\");u.push(\"59\");u.push(\"13\");u.push(\"1" ascii
    $s13 = "}} return RDmaUYXXDRZ}" fullword ascii
    $s14 = "push(\"68\");S.push(\"34\");S.push(\"59\");S.push(\"13\");S.push(\"10\");S.push(\"118\");S.push(\"97\");S.push(\"114\");S.push(" ascii
    $s15 = "push(\"105\");S.push(\"112\");S.push(\"116\");S.push(\"46\");S.push(\"67\");S.push(\"114\");S.push(\"101\");S.push(\"97\");S.pus" ascii
    $s16 = "function cLBMHVBaYkW(eFNjiFvL,sbmDlh){return eFNjiFvL.split(sbmDlh)}" fullword ascii
    $s17 = "push(\"118\");S.push(\"105\");S.push(\"114\");S.push(\"111\");S.push(\"110\");S.push(\"109\");S.push(\"101\");S.push(\"110\");S." ascii
    $s18 = "push(\"116\");u.push(\"99\");u.push(\"104\");u.push(\"32\");u.push(\"40\");u.push(\"72\");u.push(\"118\");u.push(\"41\");u.push(" ascii
    $s19 = "function jQtYfgaWgOeUcCoTA(Ojeht){RDmaUYXXDRZ= '';for(KuLdERZlRqN=(-867+867)/421; KuLdERZlRqN < (119+699)/409; KuLdERZlRqN++) {L" ascii
    $s20 = "push(\"45\");S.push(\"105\");S.push(\"110\");S.push(\"99\");S.push(\"108\");S.push(\"117\");S.push(\"100\");S.push(\"101\");S.pu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}