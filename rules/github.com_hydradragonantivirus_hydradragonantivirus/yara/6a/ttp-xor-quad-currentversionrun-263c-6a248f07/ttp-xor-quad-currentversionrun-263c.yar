rule TTP_XOR_QUAD_CurrentVersionRun_263c {
  strings:
    $key_263c = { 75 53 [2] 51 5d [2] 7a 71 [2] 54 53 [2] 40 48 [2] 4f 52 [2] 51 4f [2] 53 4e [2] 48 48 [2] 54 4f [2] 48 60 }

  condition:
    any of them
}