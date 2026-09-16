rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_181_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_181_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7870be862dcf58dde447f6cfc56daa5c969c0b650557a3dcce8bbc110f01576"

  strings:
    $s1 = "jWepezikowi geyolevaki mezekeri toh nabikakonupa rucijelilifoxu hicuyasasuvan mifawonupemex lata tabifovaji" fullword wide
    $s2 = "Biresusi himefox gawi2Gupug jusuvobediweyal rum doleyuweyumapo mejaloxugNZuv luguyubabujeyi ledehopeduziju robozomupupi yuz focu" wide
    $s3 = "WucewahezibovunVecezukawahezop kijowepunuxake xatigudifaroke gahinaf gumizizon yatumakiko lajuxujomig katawolevuw cemejecetamAMa" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}