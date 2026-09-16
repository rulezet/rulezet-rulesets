rule TTP_XOR_QUAD_CurrentVersionRun_98cc {
  strings:
    $key_98cc = { cb a3 [2] ef ad [2] c4 81 [2] ea a3 [2] fe b8 [2] f1 a2 [2] ef bf [2] ed be [2] f6 b8 [2] ea bf [2] f6 90 }

  condition:
    any of them
}