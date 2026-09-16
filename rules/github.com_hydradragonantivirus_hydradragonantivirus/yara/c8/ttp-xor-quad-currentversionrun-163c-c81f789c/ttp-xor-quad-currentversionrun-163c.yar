rule TTP_XOR_QUAD_CurrentVersionRun_163c {
  strings:
    $key_163c = { 45 53 [2] 61 5d [2] 4a 71 [2] 64 53 [2] 70 48 [2] 7f 52 [2] 61 4f [2] 63 4e [2] 78 48 [2] 64 4f [2] 78 60 }

  condition:
    any of them
}