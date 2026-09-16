rule TTP_XOR_QUAD_CurrentVersionRun_05fe {
  strings:
    $key_05fe = { 56 91 [2] 72 9f [2] 59 b3 [2] 77 91 [2] 63 8a [2] 6c 90 [2] 72 8d [2] 70 8c [2] 6b 8a [2] 77 8d [2] 6b a2 }

  condition:
    any of them
}