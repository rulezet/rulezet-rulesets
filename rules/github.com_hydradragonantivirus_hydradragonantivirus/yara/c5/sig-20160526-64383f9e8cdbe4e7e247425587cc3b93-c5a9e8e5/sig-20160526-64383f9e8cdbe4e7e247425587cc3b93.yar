rule sig_20160526_64383f9e8cdbe4e7e247425587cc3b93 {
  meta:
    description = "datamaliciousorder - file 20160526_64383f9e8cdbe4e7e247425587cc3b93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92b2fc7a2578e6068d98406d411b9d70d2999c7b22457d6152b6b8704ddb60fa"

  strings:
    $s1  = "round((Math.pow(Math.sin(157), 2) + Math.pow(Math.cos(157), 2) - 1))-840)) geCuBveOnnoErdmp += LWtWRpXesJPHsUecxsf(dNzEzACIubRGq" ascii
    $s2  = "h.pow(Math.cos(929), 2) - 1))-963)) geCuBveOnnoErdmp += ab(dNzEzACIubRGqMiDKcLdSNMI);else if (sZQPjMpVWwXKzMWqec == (904 + Math." ascii
    $s3  = "function RdkHo(HwoVvUCWPxPYF) {var TXcAoPEuhBmOieQfnNSPNlB = YVgFQWiOqLZYTZhddBWcWp.join(IkxmQQbhrUS[0]);var dNzEzACIubRGqMiDKcL" ascii
    $s4  = "function shiivFbVxZLllVW(QAVQGsmjaOFf,COsWhYMDUyGtJaZqzkE){return QAVQGsmjaOFf.charAt(COsWhYMDUyGtJaZqzkE);}" fullword ascii
    $s5  = "function TWLSNpNxUDfjklR(feuXVWYXJOevNkyNUOnkz,IhvLhYfVauu,NnDoEZkRJzgPcP){return String.fromCharCode(feuXVWYXJOevNkyNUOnkz,IhvL" ascii
    $s6  = "function TWLSNpNxUDfjklR(feuXVWYXJOevNkyNUOnkz,IhvLhYfVauu,NnDoEZkRJzgPcP){return String.fromCharCode(feuXVWYXJOevNkyNUOnkz,IhvL" ascii
    $s7  = "function BvrFZNoRLNWlMrrkHfJ(AjRyIJDOnED,obmHuloKovtGoznWpJWxU){return AjRyIJDOnED.indexOf(obmHuloKovtGoznWpJWxU);}" fullword ascii
    $s8  = "function ab(idPpdbucmrhPVLxdEt){return String.fromCharCode(idPpdbucmrhPVLxdEt);}" fullword ascii
    $s9  = "function LWtWRpXesJPHsUecxsf(zgPSYUA,lUQBV){return String.fromCharCode(zgPSYUA,lUQBV);}" fullword ascii
    $s10 = "BtxMtRK < HwoVvUCWPxPYF.length);return geCuBveOnnoErdmp;}" fullword ascii
    $s11 = "function RdkHo(HwoVvUCWPxPYF) {var TXcAoPEuhBmOieQfnNSPNlB = YVgFQWiOqLZYTZhddBWcWp.join(IkxmQQbhrUS[0]);var dNzEzACIubRGqMiDKcL" ascii
    $s12 = "MiDKcLdSNMI, yhdQl);else geCuBveOnnoErdmp += TWLSNpNxUDfjklR(dNzEzACIubRGqMiDKcLdSNMI, yhdQl, GkyjMoHYCAbiUN);} while (RnrRNvdrs" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}