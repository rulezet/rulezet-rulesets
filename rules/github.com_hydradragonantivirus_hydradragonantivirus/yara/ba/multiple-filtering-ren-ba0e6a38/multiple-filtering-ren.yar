rule multiple_filtering_ren: PDF {
  meta:
    author  = "Glenn Edwards (@hiddenillusion)"
    version = "0.2"
    weight  = 3

  strings:
    $magic  = "%PDF"
    $attrib = /\/Filter\s*(\/(ASCIIHexDecode|LZWDecode|ASCII85Decode|FlateDecode|RunLengthDecode)){2}/
  
  condition:
    $magic at 0 and $attrib
}