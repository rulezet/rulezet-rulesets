rule TTP_XOR_QUAD_CurrentVersionRun_0afe {
  strings:
    $key_0afe = { 59 91 [2] 7d 9f [2] 56 b3 [2] 78 91 [2] 6c 8a [2] 63 90 [2] 7d 8d [2] 7f 8c [2] 64 8a [2] 78 8d [2] 64 a2 }

  condition:
    any of them
}