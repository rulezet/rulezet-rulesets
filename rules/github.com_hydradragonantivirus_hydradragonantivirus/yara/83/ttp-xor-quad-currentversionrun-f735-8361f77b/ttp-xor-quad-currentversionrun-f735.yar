rule TTP_XOR_QUAD_CurrentVersionRun_f735 {
  strings:
    $key_f735 = { a4 5a [2] 80 54 [2] ab 78 [2] 85 5a [2] 91 41 [2] 9e 5b [2] 80 46 [2] 82 47 [2] 99 41 [2] 85 46 [2] 99 69 }

  condition:
    any of them
}