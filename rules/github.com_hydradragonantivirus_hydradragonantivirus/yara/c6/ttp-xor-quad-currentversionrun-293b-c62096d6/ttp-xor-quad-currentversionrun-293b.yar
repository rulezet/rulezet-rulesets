rule TTP_XOR_QUAD_CurrentVersionRun_293b {
  strings:
    $key_293b = { 7a 54 [2] 5e 5a [2] 75 76 [2] 5b 54 [2] 4f 4f [2] 40 55 [2] 5e 48 [2] 5c 49 [2] 47 4f [2] 5b 48 [2] 47 67 }

  condition:
    any of them
}