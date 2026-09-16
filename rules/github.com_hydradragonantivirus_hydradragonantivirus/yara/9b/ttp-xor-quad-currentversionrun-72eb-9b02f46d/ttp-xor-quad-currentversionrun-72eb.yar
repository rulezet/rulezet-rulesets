rule TTP_XOR_QUAD_CurrentVersionRun_72eb {
  strings:
    $key_72eb = { 21 84 [2] 05 8a [2] 2e a6 [2] 00 84 [2] 14 9f [2] 1b 85 [2] 05 98 [2] 07 99 [2] 1c 9f [2] 00 98 [2] 1c b7 }

  condition:
    any of them
}