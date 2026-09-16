rule TTP_XOR_QUAD_CurrentVersionRun_b07b {
  strings:
    $key_b07b = { e3 14 [2] c7 1a [2] ec 36 [2] c2 14 [2] d6 0f [2] d9 15 [2] c7 08 [2] c5 09 [2] de 0f [2] c2 08 [2] de 27 }

  condition:
    any of them
}