rule TTP_XOR_QUAD_CurrentVersionRun_3c3c {
  strings:
    $key_3c3c = { 6f 53 [2] 4b 5d [2] 60 71 [2] 4e 53 [2] 5a 48 [2] 55 52 [2] 4b 4f [2] 49 4e [2] 52 48 [2] 4e 4f [2] 52 60 }

  condition:
    any of them
}