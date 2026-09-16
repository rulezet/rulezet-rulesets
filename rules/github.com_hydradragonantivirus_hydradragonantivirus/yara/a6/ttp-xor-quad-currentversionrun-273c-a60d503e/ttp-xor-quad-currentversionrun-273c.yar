rule TTP_XOR_QUAD_CurrentVersionRun_273c {
  strings:
    $key_273c = { 74 53 [2] 50 5d [2] 7b 71 [2] 55 53 [2] 41 48 [2] 4e 52 [2] 50 4f [2] 52 4e [2] 49 48 [2] 55 4f [2] 49 60 }

  condition:
    any of them
}