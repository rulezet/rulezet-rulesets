rule TTP_XOR_QUAD_CurrentVersionRun_3cef {
  strings:
    $key_3cef = { 6f 80 [2] 4b 8e [2] 60 a2 [2] 4e 80 [2] 5a 9b [2] 55 81 [2] 4b 9c [2] 49 9d [2] 52 9b [2] 4e 9c [2] 52 b3 }

  condition:
    any of them
}