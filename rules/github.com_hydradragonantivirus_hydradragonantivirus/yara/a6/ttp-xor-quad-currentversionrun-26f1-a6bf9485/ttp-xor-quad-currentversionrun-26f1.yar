rule TTP_XOR_QUAD_CurrentVersionRun_26f1 {
  strings:
    $key_26f1 = { 75 9e [2] 51 90 [2] 7a bc [2] 54 9e [2] 40 85 [2] 4f 9f [2] 51 82 [2] 53 83 [2] 48 85 [2] 54 82 [2] 48 ad }

  condition:
    any of them
}