rule TTP_XOR_QUAD_CurrentVersionRun_b068 {
  strings:
    $key_b068 = { e3 07 [2] c7 09 [2] ec 25 [2] c2 07 [2] d6 1c [2] d9 06 [2] c7 1b [2] c5 1a [2] de 1c [2] c2 1b [2] de 34 }

  condition:
    any of them
}