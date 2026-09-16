rule sig_20170119_a5653c5ecc08c03fb9e29621117b3e64 {
  meta:
    description = "datamaliciousorder - file 20170119_a5653c5ecc08c03fb9e29621117b3e64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50498df8ad9da3deead99a1976af60fe7f9545106ad81a391e0c5a1b23140e7d"

  strings:
    $s1 = "var qbuloryf0 = new Function(qcomlahkojnopzosuxexwuvlycihgatdyquqkacekahycenkiqohegpelwiginvucpuvugcaqpafkokyridcavsymaguhyxiwol" ascii
    $s2 = "var qbuloryf0 = new Function(qcomlahkojnopzosuxexwuvlycihgatdyquqkacekahycenkiqohegpelwiginvucpuvugcaqpafkokyridcavsymaguhyxiwol" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}