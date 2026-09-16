rule TTP_XOR_QUAD_CurrentVersionRun_08ff {
  strings:
    $key_08ff = { 5b 90 [2] 7f 9e [2] 54 b2 [2] 7a 90 [2] 6e 8b [2] 61 91 [2] 7f 8c [2] 7d 8d [2] 66 8b [2] 7a 8c [2] 66 a3 }

  condition:
    any of them
}