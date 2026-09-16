rule TTP_XOR_WriteProcessMemory_5623 {
  strings:
    $key_5623 = { 01 51 [2] 33 73 [2] 35 46 [2] 1b 46 [2] 24 5a }

  condition:
    any of them
}