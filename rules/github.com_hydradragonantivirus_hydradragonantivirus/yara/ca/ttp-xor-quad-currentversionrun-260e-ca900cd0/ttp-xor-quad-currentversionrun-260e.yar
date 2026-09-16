rule TTP_XOR_QUAD_CurrentVersionRun_260e {
  strings:
    $key_260e = { 75 61 [2] 51 6f [2] 7a 43 [2] 54 61 [2] 40 7a [2] 4f 60 [2] 51 7d [2] 53 7c [2] 48 7a [2] 54 7d [2] 48 52 }

  condition:
    any of them
}