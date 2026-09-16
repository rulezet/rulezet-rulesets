rule TTP_XOR_WriteProcessMemory_61cc {
  strings:
    $key_61cc = { 36 be [2] 04 9c [2] 02 a9 [2] 2c a9 [2] 13 b5 }

  condition:
    any of them
}