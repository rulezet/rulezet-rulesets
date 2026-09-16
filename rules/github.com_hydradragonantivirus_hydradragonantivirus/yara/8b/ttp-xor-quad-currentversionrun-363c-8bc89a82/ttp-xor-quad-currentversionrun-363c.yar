rule TTP_XOR_QUAD_CurrentVersionRun_363c {
  strings:
    $key_363c = { 65 53 [2] 41 5d [2] 6a 71 [2] 44 53 [2] 50 48 [2] 5f 52 [2] 41 4f [2] 43 4e [2] 58 48 [2] 44 4f [2] 58 60 }

  condition:
    any of them
}