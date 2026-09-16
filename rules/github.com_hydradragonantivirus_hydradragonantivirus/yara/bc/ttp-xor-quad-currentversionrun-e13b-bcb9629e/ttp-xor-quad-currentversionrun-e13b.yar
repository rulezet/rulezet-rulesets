rule TTP_XOR_QUAD_CurrentVersionRun_e13b {
  strings:
    $key_e13b = { b2 54 [2] 96 5a [2] bd 76 [2] 93 54 [2] 87 4f [2] 88 55 [2] 96 48 [2] 94 49 [2] 8f 4f [2] 93 48 [2] 8f 67 }

  condition:
    any of them
}