rule TTP_XOR_QUAD_CurrentVersionRun_27ff {
  strings:
    $key_27ff = { 74 90 [2] 50 9e [2] 7b b2 [2] 55 90 [2] 41 8b [2] 4e 91 [2] 50 8c [2] 52 8d [2] 49 8b [2] 55 8c [2] 49 a3 }

  condition:
    any of them
}