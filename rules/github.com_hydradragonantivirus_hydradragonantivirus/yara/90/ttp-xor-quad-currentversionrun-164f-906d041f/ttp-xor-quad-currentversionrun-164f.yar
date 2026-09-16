rule TTP_XOR_QUAD_CurrentVersionRun_164f {
  strings:
    $key_164f = { 45 20 [2] 61 2e [2] 4a 02 [2] 64 20 [2] 70 3b [2] 7f 21 [2] 61 3c [2] 63 3d [2] 78 3b [2] 64 3c [2] 78 13 }

  condition:
    any of them
}