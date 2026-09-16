rule TTP_XOR_QUAD_CurrentVersionRun_f13c {
  strings:
    $key_f13c = { a2 53 [2] 86 5d [2] ad 71 [2] 83 53 [2] 97 48 [2] 98 52 [2] 86 4f [2] 84 4e [2] 9f 48 [2] 83 4f [2] 9f 60 }

  condition:
    any of them
}