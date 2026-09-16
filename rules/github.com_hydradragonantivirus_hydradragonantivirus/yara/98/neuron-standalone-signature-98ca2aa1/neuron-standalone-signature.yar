rule neuron_standalone_signature {
 meta:
   description = "Rule for detection of Neuron based on a standalone signature from .NET metadata"
   author = "NCSC UK"
   reference = "https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB"
   reference2 = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
   hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
 strings:
   $a = {eb073d151231011234080e12818d1d051281311d1281211d1281211d128121081d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281}
   $dotnetMagic = "BSJB" ascii
 condition:
   (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them
}