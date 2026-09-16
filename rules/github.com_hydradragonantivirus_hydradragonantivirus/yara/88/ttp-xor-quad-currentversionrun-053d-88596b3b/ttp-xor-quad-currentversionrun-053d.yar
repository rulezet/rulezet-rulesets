rule TTP_XOR_QUAD_CurrentVersionRun_053d {
  strings:
    $key_053d = { 56 52 [2] 72 5c [2] 59 70 [2] 77 52 [2] 63 49 [2] 6c 53 [2] 72 4e [2] 70 4f [2] 6b 49 [2] 77 4e [2] 6b 61 }

  condition:
    any of them
}