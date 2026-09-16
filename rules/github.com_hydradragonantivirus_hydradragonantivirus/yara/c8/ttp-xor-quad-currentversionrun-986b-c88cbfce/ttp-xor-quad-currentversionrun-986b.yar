rule TTP_XOR_QUAD_CurrentVersionRun_986b {
  strings:
    $key_986b = { cb 04 [2] ef 0a [2] c4 26 [2] ea 04 [2] fe 1f [2] f1 05 [2] ef 18 [2] ed 19 [2] f6 1f [2] ea 18 [2] f6 37 }

  condition:
    any of them
}