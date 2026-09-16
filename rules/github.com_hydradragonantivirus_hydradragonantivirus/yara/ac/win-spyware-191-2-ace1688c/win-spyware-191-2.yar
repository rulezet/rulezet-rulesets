rule Win_Spyware_191_2
{
strings:
	$a0 = { 68902140008d85bcfaffff50ffd7e85c06000085c075148d85bcfaffff50e8fa0300003d3104000059755a }


condition:
	$a0
}