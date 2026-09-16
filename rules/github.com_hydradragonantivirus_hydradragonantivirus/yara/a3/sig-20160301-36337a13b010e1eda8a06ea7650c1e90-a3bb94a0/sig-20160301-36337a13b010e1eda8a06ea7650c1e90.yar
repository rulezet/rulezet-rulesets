rule sig_20160301_36337a13b010e1eda8a06ea7650c1e90 {
  meta:
    description = "datamaliciousorder - file 20160301_36337a13b010e1eda8a06ea7650c1e90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "478d5a90fee0bedb48bf4c2ff374728c7dcdc066b348f12f899087b01c7e4bb9"

  strings:
    $s1 = " robotDog[(\"c\" + \"\\u0061\" + \"\\u006ed\\u0069\" + \"da\\u0074\" + \"e\", \"c\\u0061\" + \"\\u0070\" + \"\\u0074\\u0061i\" +" ascii
    $s2 = " robotDog[(\"c\" + \"\\u0061\" + \"\\u006ed\\u0069\" + \"da\\u0074\" + \"e\", \"c\\u0061\" + \"\\u0070\" + \"\\u0074\\u0061i\" +" ascii
    $s3 = "while (parkMoral[(\"\\u0066\" + \"\\u0061\" + \"c\\u0074\\u006f\\u0072\", \"\\u0061\\u0071ua\" + \"ri\" + \"\\u0075m\", \"\\u007" ascii
    $s4 = "robotDog = (((49 / 49) * 1), this);" fullword ascii
    $s5 = "while (parkMoral[(\"\\u0066\" + \"\\u0061\" + \"c\\u0074\\u006f\\u0072\", \"\\u0061\\u0071ua\" + \"ri\" + \"\\u0075m\", \"\\u007" ascii
    $s6 = "} catch (theoremMassive) {};" fullword ascii

  condition:
    uint16(0) == 0x6f72 and
    all of them
}