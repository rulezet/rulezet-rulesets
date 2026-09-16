rule TTP_XOR_QUAD_CurrentVersionRun_223c {
  strings:
    $key_223c = { 71 53 [2] 55 5d [2] 7e 71 [2] 50 53 [2] 44 48 [2] 4b 52 [2] 55 4f [2] 57 4e [2] 4c 48 [2] 50 4f [2] 4c 60 }

  condition:
    any of them
}