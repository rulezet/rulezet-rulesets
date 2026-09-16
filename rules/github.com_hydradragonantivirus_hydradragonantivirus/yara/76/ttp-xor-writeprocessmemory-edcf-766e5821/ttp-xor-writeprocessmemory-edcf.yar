rule TTP_XOR_WriteProcessMemory_edcf {
  strings:
    $key_edcf = { ba bd [2] 88 9f [2] 8e aa [2] a0 aa [2] 9f b6 }

  condition:
    any of them
}